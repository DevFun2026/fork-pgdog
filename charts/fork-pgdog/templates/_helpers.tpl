{{- define "fork-pgdog.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fork-pgdog.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "fork-pgdog.labels" -}}
{{ include "fork-pgdog.selectorLabels" . }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}

{{- define "fork-pgdog.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "fork-pgdog.validate" -}}
{{- $count := 0 -}}
{{- if .Values.config.pgdogToml | trim -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if .Values.config.existingConfigMap -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if .Values.config.existingSecret -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if ne $count 1 -}}{{ fail "config: select exactly one non-empty pgdogToml, existingConfigMap or existingSecret" }}{{- end -}}
{{- if eq .Values.containerPort .Values.healthcheckPort -}}{{ fail "proxy and health port must be different" }}{{- end -}}
{{- end -}}

{{- define "fork-pgdog.securityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "fork-pgdog.volumeMounts" -}}
- name: config
  mountPath: /etc/pgdog/config
  readOnly: true
- name: users
  mountPath: /etc/pgdog/users
  readOnly: true
- name: tmp
  mountPath: /tmp
{{- if .Values.tls.existingSecret }}
- name: tls
  mountPath: /etc/pgdog/tls
  readOnly: true
{{- end }}
{{- end -}}
