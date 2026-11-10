{{- define "sd.name" -}}{{ .Release.Name }}{{- end -}}
{{- define "sd.apiName" -}}{{ include "sd.name" . }}-api{{- end -}}
{{- define "sd.webName" -}}{{ include "sd.name" . }}-web{{- end -}}
{{- define "sd.apiSA" -}}{{ if .Values.api.serviceAccount.name }}{{ .Values.api.serviceAccount.name }}{{ else }}{{ include "sd.apiName" . }}{{ end }}{{- end -}}
{{- define "sd.webSA" -}}{{ if .Values.web.serviceAccount.name }}{{ .Values.web.serviceAccount.name }}{{ else }}{{ include "sd.webName" . }}{{ end }}{{- end -}}
{{- define "sd.socket" -}}unix://{{ .Values.spiffe.socketDir }}/{{ .Values.spiffe.socketName }}{{- end -}}
{{- define "sd.allowedIds" -}}
{{- if .Values.spiffe.allowedIds -}}{{ toYaml .Values.spiffe.allowedIds }}
{{- else -}}- spiffe://{{ .Values.spiffe.trustDomain }}/ns/{{ .Release.Namespace }}/sa/{{ include "sd.webSA" . }}{{- end -}}
{{- end -}}
{{/* downward API env shared by both pods */}}
{{- define "sd.podEnv" -}}
- {name: POD_NAME, valueFrom: {fieldRef: {fieldPath: metadata.name}}}
- {name: POD_NAMESPACE, valueFrom: {fieldRef: {fieldPath: metadata.namespace}}}
- {name: NODE_NAME, valueFrom: {fieldRef: {fieldPath: spec.nodeName}}}
- {name: POD_SERVICE_ACCOUNT, valueFrom: {fieldRef: {fieldPath: spec.serviceAccountName}}}
{{- end -}}
{{- define "sd.spiffeVolume" -}}
- name: spiffe-workload-api
{{ toYaml .Values.spiffe.workloadApiVolume | indent 2 }}
{{- end -}}
