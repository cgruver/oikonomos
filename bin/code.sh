function createQuarkusProject() {

  # GIT_API=${GIT_API:-https://api.github.com/user/repos}
  # GIT_KEYS=${GIT_KEYS:-${HOME}/.git_token}
  BASE_EXTENSIONS="quarkus-resteasy-jackson,quarkus-config-yaml,quarkus-rest-client,quarkus-smallrye-health"
  ADD_EXTENSIONS=""
  
  for i in "$@"
  do
    case $i in
      -p=*|--project=*)
        PROJECT="${i#*=}"
      ;;
      -g=*|--group-id=*)
        GROUP_ID="${i#*=}"
      ;;
      -q=*|--quarkus-ver=*)
        QUARKUS_VERSION="${i#*=}"
      ;;
      -x=*|--extensions=*)
        ADD_EXTENSIONS=",${i#*=}"
      # -u=*|--git-url=*)
      #   GIT_URL="${i#*=}"
      # ;;
      # -o=*|--git-org=*)
      #   GIT_API="https://api.github.com/orgs/${i#*=}/repos"
      # ;;
    esac
  done

  JAVA_VER=${JAVA_VER:-17}

  quarkus create app --maven --java=${JAVA_VER} --no-wrapper --no-code --package-name=${GROUP_ID}.${PROJECT} --extensions=${BASE_EXTENSIONS}${ADD_EXTENSIONS}  ${GROUP_ID}:${PROJECT}:0.1
  
  cd ${PROJECT}
  touch README.md
  mkdir -p ./src/test/java/${GROUP_ID//.//}/${PROJECT}
  touch ./src/test/java/${GROUP_ID//.//}/.gitignore
  mkdir -p ./src/main/java/${GROUP_ID//.//}/${PROJECT}/{aop,api,dto,colaborators,event,mapper,model,service}
  touch ./src/main/java/${GROUP_ID//.//}/${PROJECT}/{aop,api,dto,colaborators,event,mapper,model,service}/.gitignore
  cd -
  # gitInit ${PROJECT}
}

function gitInit(){
    local project=${1}
    git init
    git add .
    git commit -m "create repo"
    curl -u ${GIT_USER}:${ACCESS_TOKEN} -X POST ${GIT_API} -d "{\"name\":\"${project}\",\"private\":false}"
    git remote add origin ${GIT_URL}/${project}.git
    git branch -M main
    git push -u origin main
}
