{{/*
  ClamAV sidecar.

  Renders the container spec, the shared volume mount, and the
  emptyDir volume entry that exposes the clamd Unix socket to every
  other container in the pod. The API_Server connects to the socket
  through `internal/cloud/storage.ClamAVScanner` to scan every upload
  before it reaches S3 (Requirement 20.8 / design.md "Security
  Hardening → ClamAV").

  Three nested helpers are provided so `deployment.yaml` can compose
  them without duplicating the value lookups:

    - `xalgorix-cloud.clamav.container` — full container spec including
      volume mounts, probes, and resources.
    - `xalgorix-cloud.clamav.volumeMount` — the read-write socket
      directory mount used by the API_Server container so it can dial
      the socket at `clamav.socketPath`.
    - `xalgorix-cloud.clamav.volume` — the `emptyDir` volume backing
      the socket directory. Pod-scoped, never persisted.
*/}}

{{- define "xalgorix-cloud.clamav.socketDir" -}}
{{- $path := .Values.clamav.socketPath | default "/run/clamd/clamd.sock" -}}
{{- regexReplaceAll "/[^/]+$" $path "" -}}
{{- end -}}

{{- define "xalgorix-cloud.clamav.container" -}}
- name: clamav
  image: "{{ .Values.clamav.image.repository }}:{{ .Values.clamav.image.tag }}"
  imagePullPolicy: {{ .Values.clamav.image.pullPolicy | default "IfNotPresent" }}
  # The upstream image binds clamd to TCP 3310 by default. The
  # CLAMD_CONF_LocalSocket env var rewrites clamd.conf at startup so
  # the daemon ALSO listens on the shared Unix socket the API_Server
  # connects to via `internal/cloud/storage.ClamAVScanner`.
  env:
    - name: CLAMD_CONF_LocalSocket
      value: {{ .Values.clamav.socketPath | quote }}
    - name: CLAMD_CONF_LocalSocketMode
      value: "660"
    - name: CLAMD_CONF_StreamMaxLength
      # 25 MiB — comfortably above the 2 MiB logo and 1 MiB target list
      # limits enforced upstream by the API_Server body limit middleware.
      value: "25M"
  ports:
    - name: clamd-tcp
      containerPort: 3310
      protocol: TCP
  livenessProbe:
{{- toYaml .Values.clamav.livenessProbe | nindent 4 }}
  readinessProbe:
{{- toYaml .Values.clamav.readinessProbe | nindent 4 }}
  startupProbe:
{{- toYaml .Values.clamav.startupProbe | nindent 4 }}
  resources:
{{- toYaml .Values.clamav.resources | nindent 4 }}
  securityContext:
    allowPrivilegeEscalation: false
    runAsNonRoot: true
    runAsUser: 100
    runAsGroup: 100
    capabilities:
      drop: ["ALL"]
    seccompProfile:
      type: RuntimeDefault
  volumeMounts:
    - name: clamav-socket
      mountPath: {{ include "xalgorix-cloud.clamav.socketDir" . }}
    - name: clamav-data
      mountPath: /var/lib/clamav
{{- end -}}

{{- define "xalgorix-cloud.clamav.volumeMount" -}}
- name: clamav-socket
  mountPath: {{ include "xalgorix-cloud.clamav.socketDir" . }}
  readOnly: false
{{- end -}}

{{- define "xalgorix-cloud.clamav.volume" -}}
- name: clamav-socket
  emptyDir:
    medium: Memory
    sizeLimit: 4Mi
- name: clamav-data
  emptyDir:
    sizeLimit: 1Gi
{{- end -}}
