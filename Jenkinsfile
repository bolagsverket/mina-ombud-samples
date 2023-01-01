pipeline {
    agent { label 'dockerbuild' }

    parameters {
        credentials(name: 'REGISTRY_CREDENTIALS_ID',
            credentialType: 'com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl',
            required: true)
        credentials(name: 'CHART_REPO_CREDENTIALS_ID',
            credentialType: 'com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl',
            required: false)
        string(name: 'REGISTRY', defaultValue: '', description: 'Docker registry')
        string(name: 'CHART_REPO', defaultValue: '', description: 'Chart repo')
        string(name: 'IMAGE', defaultValue: 'minaombud/python-sample', description: 'Docker image name')
        booleanParam(name: 'PUSH', defaultValue: false, description: 'Push artifacts')
        booleanParam(name: 'OVERWRITE', defaultValue: false, description: 'Overwrite helm chart')
    }

    stages {
        stage('Build') {
            environment {
                REGISTRY_CREDENTIALS = credentials("${params.REGISTRY_CREDENTIALS_ID}")
                CHART_REPO_CREDENTIALS = credentials("${params.CHART_REPO_CREDENTIALS_ID ?: params.REGISTRY_CREDENTIALS_ID}")
            }
            steps {
                script {
                    def addenv = []
                    if (params.REGISTRY && !params.CHART_REPO) {
                        def project = params.IMAGE.replaceAll('/.*', '')
                        addenv << "CHART_REPO=https://${params.REGISTRY}/chartrepo/$project"
                    }
                    withEnv(addenv) {
                        sh './python/build-docker-image.sh'
                        sh './python/build-helm-chart.sh'
                    }
                }
            }
        }
    }

    post {
        cleanup {
            dir(WORKSPACE) {
                deleteDir()
            }
        }
    }
}
