// Jenkinsfile — CI/CD de s3-crypto-gateway para Jenkins corporativo.
// Firma POR CLAVE (sin OIDC): tests → govulncheck → build podman → Trivy →
// push → firma+SBOM+provenance (tools/ci/attest.sh).
// Agente (label 'podman'): podman, go >= 1.25, trivy, cosign, jq, git.
// Credenciales: registry-creds (user/pass), cosign-key (file), cosign-pass (text).
pipeline {
  agent { label 'podman' }

  parameters {
    string(name: 'REGISTRY', defaultValue: 'registry.example.com/security', description: 'Registro destino')
    string(name: 'VERSION',  defaultValue: '', description: 'Tag (vacío = git short SHA)')
    booleanParam(name: 'PUSH', defaultValue: false, description: 'Push al registro')
    booleanParam(name: 'SIGN', defaultValue: false, description: 'Firma + SBOM + provenance')
  }

  options { timestamps(); disableConcurrentBuilds() }

  stages {
    stage('Versión') {
      steps {
        script { env.V = params.VERSION ?: sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim() }
      }
    }
    stage('Tests Go') {
      steps { sh 'go vet ./... && go test ./...' }
    }
    stage('govulncheck') {
      steps { sh 'go run golang.org/x/vuln/cmd/govulncheck@latest ./...' }
    }
    stage('Build') {
      steps { sh 'podman build --pull -t "${REGISTRY}/s3-crypto-gateway:${V}" .' }
    }
    stage('Trivy') {
      steps {
        sh '''
          podman save --format docker-archive -o /tmp/scan.tar "${REGISTRY}/s3-crypto-gateway:${V}"
          trivy image --input /tmp/scan.tar --severity CRITICAL --exit-code 1 --quiet
          rm -f /tmp/scan.tar
        '''
      }
    }
    stage('Push') {
      when { expression { params.PUSH } }
      steps {
        withCredentials([usernamePassword(credentialsId: 'registry-creds', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
          sh '''
            echo "$REG_PASS" | podman login "${REGISTRY%%/*}" -u "$REG_USER" --password-stdin
            podman push "${REGISTRY}/s3-crypto-gateway:${V}"
          '''
        }
      }
    }
    stage('Firma + SBOM + provenance') {
      when { expression { params.PUSH && params.SIGN } }
      steps {
        withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY'),
                         string(credentialsId: 'cosign-pass', variable: 'COSIGN_PASSWORD')]) {
          sh '''
            mkdir -p sbom
            SBOM_OUT="sbom/s3-crypto-gateway-${V}.cdx.json" \
            BUILDER_ID="urn:builder:jenkins:${JOB_NAME}" \
              tools/ci/attest.sh "${REGISTRY}/s3-crypto-gateway:${V}"
          '''
        }
        archiveArtifacts artifacts: 'sbom/*.cdx.json', fingerprint: true
      }
    }
  }

  post { always { cleanWs(deleteDirs: true, notFailBuild: true) } }
}
