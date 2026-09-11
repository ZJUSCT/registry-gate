{{/* registry-gate chart helpers */}}

{{- define "registry-gate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "registry-gate.fullname" -}}
{{- default "registry-gate" .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "registry-gate.labels" -}}
app.kubernetes.io/name: {{ include "registry-gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gate
{{- end -}}

{{- define "registry-gate.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
