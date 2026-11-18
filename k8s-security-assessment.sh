#!/usr/bin/env bash
# Kubernetes security posture collector for clusters you administer.
# K3s-specific encryption and optional kube-bench checks run locally.
set -uo pipefail
umask 077

if ! command -v jq >/dev/null 2>&1 || ! jq -n '1 | IN(1)' >/dev/null 2>&1; then
  echo "jq 1.6 veya üstü gerekiyor." >&2
  exit 1
fi

OUT="k8s-assessment-$(date +%Y%m%d-%H%M%S)"
# Refuse an existing output path, including symlinks.
mkdir -- "$OUT" || exit 1
mkdir -- "$OUT"/{raw,rbac,podsec,netpol,benchmark} || exit 1
LOG="$OUT/scan.log"
touch "$LOG" || exit 1

log()  { echo "[*] $*" | tee -a "$LOG"; }
warn() { echo "[!] $*" | tee -a "$LOG"; }
ok()   { echo "[OK] $*" | tee -a "$LOG"; }

if [[ -z "${KUBECONFIG:-}" && -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

log "Çıktı dizini: $OUT"

if ! command -v kubectl >/dev/null 2>&1; then
  if command -v k3s >/dev/null 2>&1; then
    log "kubectl bulunamadı, 'k3s kubectl' alias'ı kullanılacak"
    kubectl() { k3s kubectl "$@"; }
    export -f kubectl
  else
    warn "HATA: kubectl/k3s bulunamadı, devam edilemiyor"; exit 1
  fi
fi

kubectl --request-timeout=15s get --raw=/version >/dev/null 2>&1 || { warn "HATA: cluster'a bağlanılamıyor (KUBECONFIG/izin kontrol edin)"; exit 1; }
ok "Cluster bağlantısı doğrulandı: $(kubectl config current-context 2>/dev/null)"

# ============================================================= 1. ENVANTER
log "=== 1/6: Temel envanter toplanıyor ==="
# GİZLİLİK: Diske yazılmadan önce her nesneden şunlar temizlenir:
#  - last-applied-configuration annotation'ı (secret manifest'i içerebilir)
#  - container env[].value düz metin değerleri → "<redacted len=N>"
#    (true/false/yes/no gibi bayrak değerleri analiz için korunur)
SANITIZE='
  def redact_env: if (.value|type)=="string" and ((.value|test("^(true|false|yes|no)$";"i"))|not)
                  then .value = "<redacted len=\(.value|length)>" else . end;
  def clean_containers: (.containers[]?, .initContainers[]?, .ephemeralContainers[]?) |= (if .env then .env |= map(redact_env) else . end);
  .items |= map(
    (.metadata.annotations |= (if . then del(.["kubectl.kubernetes.io/last-applied-configuration"]) else . end))
    | if .spec.containers then .spec |= clean_containers else . end
    | if .spec.template.spec then .spec.template.spec |= clean_containers else . end
    | if .spec.jobTemplate.spec.template.spec then .spec.jobTemplate.spec.template.spec |= clean_containers else . end
  )'

incomplete=0
for r in nodes pods serviceaccounts roles clusterroles rolebindings clusterrolebindings \
         services endpointslices persistentvolumes persistentvolumeclaims namespaces \
         daemonsets deployments statefulsets cronjobs jobs networkpolicies ingresses; do
  if kubectl get "$r" -A -o json 2>>"$OUT/raw/$r.err" | jq -e "$SANITIZE" > "$OUT/raw/$r.json" 2>>"$OUT/raw/$r.err" \
     && [[ -s "$OUT/raw/$r.json" ]]; then
    rm -f "$OUT/raw/$r.err"
    echo "  $r: $(jq '.items|length' "$OUT/raw/$r.json" 2>/dev/null || echo '?')"
  else
    incomplete=1
    warn "  $r: toplanamadı ($(head -c 100 "$OUT/raw/$r.err" | tr '\n' ' '))"
    echo '{"items":[]}' > "$OUT/raw/$r.json"
  fi
done

kubectl version -o json > "$OUT/raw/version.json" 2>/dev/null
kubectl get nodes -o wide > "$OUT/raw/nodes_wide.txt" 2>/dev/null

# ============================================================= 2. RBAC DENETİMİ
log "=== 2/6: RBAC aşırı-yetki taraması ==="
jq -s '
  .[0].items as $cr | .[1].items as $r | .[2].items as $crb | .[3].items as $rb |
  def ruleRisk(rule):
    (rule.verbs // [] | any(. == "*")) as $wv |
    (rule.resources // [] | any(. == "*")) as $wr |
    {
      wildcard_verb: $wv, wildcard_resource: $wr,
      secrets_get: ((rule.resources // [] | any(. == "secrets")) and (rule.verbs // [] | any(IN("get","list","watch","*")))),
      pods_exec: (rule.resources // [] | any(. == "pods/exec")),
      impersonate: ((rule.resources // [] | any(. == "*" or . == "users" or . == "groups" or . == "serviceaccounts")) and (rule.verbs // [] | any(. == "impersonate" or . == "*"))),
      bind_escalate: ((rule.verbs // [] | any(IN("bind","escalate"))) or ((rule.resources // [] | any(IN("clusterrolebindings","rolebindings","clusterroles","roles"))) and (rule.verbs // [] | any(IN("create","update","patch","*"))))),
      create_pods: ((rule.resources // [] | any(IN("pods","deployments","daemonsets","statefulsets","jobs","cronjobs","replicasets"))) and (rule.verbs // [] | any(IN("create","*"))))
    };
  [
    ($cr[] | select(.rules != null) | {kind:"ClusterRole", name:.metadata.name, risky_rules:[.rules[] | ruleRisk(.) | select(.wildcard_verb or .wildcard_resource or .secrets_get or .pods_exec or .impersonate or .bind_escalate or .create_pods)]} | select(.risky_rules | length > 0)),
    ($r[]  | select(.rules != null) | {kind:"Role", namespace:.metadata.namespace, name:.metadata.name, risky_rules:[.rules[] | ruleRisk(.) | select(.wildcard_verb or .wildcard_resource or .secrets_get or .pods_exec or .impersonate or .bind_escalate or .create_pods)]} | select(.risky_rules | length > 0))
  ] as $risky_roles |
  [
    ($crb[] | {kind:"ClusterRoleBinding", name:.metadata.name, role:.roleRef.name, subjects:(.subjects // [])} | select(.role == "cluster-admin")),
    ($rb[]  | {kind:"RoleBinding", namespace:.metadata.namespace, name:.metadata.name, role:.roleRef.name, subjects:(.subjects // [])} | select(.role == "cluster-admin" or (.role | test("admin|edit"))))
  ] as $admin_bindings |
  {risky_roles: $risky_roles, admin_or_cluster_admin_bindings: $admin_bindings}
' "$OUT/raw/clusterroles.json" "$OUT/raw/roles.json" "$OUT/raw/clusterrolebindings.json" "$OUT/raw/rolebindings.json" \
  > "$OUT/rbac/risky_rbac.json" 2>>"$LOG" || {
    incomplete=1
    warn "RBAC jq analizi başarısız"
  }

# default SA'ların otomatik token mount durumu
# NOT: '//' jq operatörü false'u da "yok" sayar; explicit false (güvenli, kapalı)
# yanlışlıkla "unset(=true)" görünmesin diye if/then/else kullanılıyor.
jq '[.items[] | select(.metadata.name=="default") | {namespace:.metadata.namespace, automountServiceAccountToken: (if .automountServiceAccountToken == null then "unset(=true)" else .automountServiceAccountToken end)}]' \
  "$OUT/raw/serviceaccounts.json" > "$OUT/rbac/default_sa_automount.json" 2>>"$LOG" || {
    incomplete=1
    warn "ServiceAccount jq analizi başarısız"
  }

# anonim / default SA yetki testi
kubectl auth can-i --list --as=system:anonymous > "$OUT/rbac/anonymous_can_i.txt" 2>&1
kubectl auth can-i --list --as=system:serviceaccount:default:default -n default > "$OUT/rbac/default_sa_can_i.txt" 2>&1
ok "RBAC analizi tamamlandı → $OUT/rbac/"

# ============================================================= 3. POD SECURITY
log "=== 3/6: Pod/Container güvenlik konfigürasyonu taranıyor ==="
# NOT: boolean alanlarda jq '//' yerine if/then/else kullanılıyor çünkü '//'
# explicit 'false'u da boş sayıp varsayılana düşer — bu, "allowPrivilegeEscalation:
# false" gibi GÜVENLİ açık ayarları yanlışlıkla riskli gösterirdi.
if jq '[.items[] |
  . as $pod |
  (($pod.spec.containers // []) + ($pod.spec.initContainers // []) + ($pod.spec.ephemeralContainers // [])) as $containers |
  {
    namespace: $pod.metadata.namespace, pod: $pod.metadata.name,
    hostNetwork: ($pod.spec.hostNetwork // false),
    hostPID: ($pod.spec.hostPID // false),
    hostIPC: ($pod.spec.hostIPC // false),
    shareProcessNamespace: ($pod.spec.shareProcessNamespace // false),
    hostPathVolumes: [$pod.spec.volumes[]? | select(.hostPath != null) | {name, path:.hostPath.path}],
    serviceAccountName: ($pod.spec.serviceAccountName // "default"),
    automountServiceAccountToken: (if $pod.spec.automountServiceAccountToken == null then "unset(=true)" else $pod.spec.automountServiceAccountToken end),
    risky_containers: [$containers[] |
      (.securityContext.privileged == true) as $isPriv |
      ((.securityContext.allowPrivilegeEscalation == null) or (.securityContext.allowPrivilegeEscalation == true)) as $isApe |
      ((if .securityContext.runAsNonRoot != null then .securityContext.runAsNonRoot else ($pod.spec.securityContext.runAsNonRoot // false) end) == false) as $isRoot |
      (((.securityContext.capabilities.add // []) | length) > 0) as $hasCaps |
      select($isPriv or $isApe or $isRoot or $hasCaps) | {
        name,
        privileged: $isPriv,
        allowPrivilegeEscalation: (if .securityContext.allowPrivilegeEscalation == null then "unset(=true)" else .securityContext.allowPrivilegeEscalation end),
        runAsNonRoot: ($isRoot | not),
        addedCapabilities: (.securityContext.capabilities.add // []),
        readOnlyRootFilesystem: (.securityContext.readOnlyRootFilesystem // false)
      }]
  } | select(.hostNetwork or .hostPID or .hostIPC or .shareProcessNamespace or (.hostPathVolumes|length>0) or (.risky_containers|length>0))
]' "$OUT/raw/pods.json" > "$OUT/podsec/risky_pods.json" 2>>"$LOG"; then
  ok "Pod güvenlik taraması tamamlandı → $OUT/podsec/risky_pods.json ($(jq length "$OUT/podsec/risky_pods.json" 2>/dev/null) riskli pod)"
else
  incomplete=1
  warn "Pod güvenlik jq analizi başarısız"
fi

# ============================================================= 4. NETWORK POLICY KAPSAMI
log "=== 4/6: NetworkPolicy kapsam analizi ==="
if [[ -e "$OUT/raw/namespaces.err" || -e "$OUT/raw/networkpolicies.err" ]]; then
  echo '{"status":"unavailable"}' > "$OUT/netpol/coverage.json"
  warn "NetworkPolicy kapsamı için gerekli envanter alınamadı"
else
  jq -s '
    (.[0].items | map(.metadata.name) | unique) as $all_ns |
    (.[1].items | map(.metadata.namespace) | unique) as $ns_with_policy |
    {all_namespaces: $all_ns, namespaces_without_any_networkpolicy: ($all_ns - $ns_with_policy)}
  ' "$OUT/raw/namespaces.json" "$OUT/raw/networkpolicies.json" > "$OUT/netpol/coverage.json" 2>>"$LOG" || {
    incomplete=1
    warn "NetworkPolicy kapsam analizi başarısız"
  }
fi

# ============================================================= 5. SECRETS / ENCRYPTION AT REST
log "=== 5/6: Secret-at-rest şifreleme kontrolü ==="
if command -v k3s >/dev/null 2>&1; then
  k3s secrets-encrypt status > "$OUT/raw/k3s_secrets_encryption.txt" 2>&1 \
    && ok "K3s şifreleme durumu alındı" \
    || warn "K3s şifreleme durumu alınamadı; sunucu düğümü ve yerel izinleri kontrol edin"
else
  warn "K3s şifreleme kontrolü atlandı; k3s binary bulunamadı"
fi

# ============================================================= 6. CIS BENCHMARK (kube-bench, çevrimdışı)
# Node'un internet erişimi yoksa kube-bench release tar.gz'si önceden ~/kube-bench/ altına
# açılmış olmalı (içinde 'kube-bench' binary'si ve 'cfg/' dizini).
log "=== 6/6: CIS Benchmark (kube-bench) ==="
KB_DIR="${KB_DIR:-${HOME:-}/kube-bench}"
if [[ -x "$KB_DIR/kube-bench" && -d "$KB_DIR/cfg" ]]; then
  "$KB_DIR/kube-bench" run --config-dir "$KB_DIR/cfg" --json > "$OUT/benchmark/kube-bench.json" 2>"$OUT/benchmark/kube-bench.err" \
    && ok "kube-bench çalıştı → $OUT/benchmark/kube-bench.json" \
    || warn "kube-bench hata verdi, bkz. $OUT/benchmark/kube-bench.err"
elif command -v kube-bench >/dev/null 2>&1; then
  kube-bench run --json > "$OUT/benchmark/kube-bench.json" 2>"$OUT/benchmark/kube-bench.err" \
    && ok "kube-bench çalıştı" || warn "kube-bench hata verdi, bkz. $OUT/benchmark/kube-bench.err"
else
  warn "kube-bench bulunamadı ($KB_DIR) — bu bölüm raporda 'veri yok' olarak işaretlenecek"
  echo '{"note":"kube-bench not available on this node"}' > "$OUT/benchmark/kube-bench.json"
fi

# ============================================================= ÖZET
log "=== Tamamlandı ==="
# Reserve the archive path without overwriting an existing file or symlink.
(set -o noclobber; : > "${OUT}.tar.gz") || exit 1
tar -czf "${OUT}.tar.gz" "$OUT/" 2>>"$LOG" || exit 1
ok "Arşiv: ${OUT}.tar.gz"
if (( incomplete )); then
  warn "Envanter veya analiz eksik. Ayrıntılar için scan.log ve .err dosyalarını inceleyin."
  exit 2
fi
