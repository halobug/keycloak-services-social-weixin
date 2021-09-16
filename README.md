# keycloak-social-wechat

* 安装步骤:
* 添加jar包到Keycloak服务:
  * `$ cp release/${version}/keycloak-social-wechat-${version}.jar _KEYCLOAK_HOME_/providers/`

* 添加模板文件到Keycloak服务:
  1. `$ cp templates/realm-identity-provider-wechat.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
  1. `$ cp templates/realm-identity-provider-wechat-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`

* 如果使用docker, 可使用
```
docker cp keycloak-social-wechat-${version}.jar ${keycloak-container-id}:/opt/jboss/keycloak/providers/
```
  
