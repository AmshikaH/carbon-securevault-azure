# Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

rm -r "dependencies"
mkdir "dependencies"
cd "dependencies"
curl https://repo1.maven.org/maven2/com/azure/azure-core/1.20.0/azure-core-1.20.0.jar -o azure-core-1.20.0.jar
curl https://repo1.maven.org/maven2/com/azure/azure-core-http-okhttp/1.7.5/azure-core-http-okhttp-1.7.5.jar -o azure-core-http-okhttp-1.7.5.jar
curl https://repo1.maven.org/maven2/com/azure/azure-identity/1.3.6/azure-identity-1.3.6.jar -o azure-identity-1.3.6.jar
curl https://repo1.maven.org/maven2/com/azure/azure-security-keyvault-secrets/4.3.4/azure-security-keyvault-secrets-4.3.4.jar -o azure-security-keyvault-secrets-4.3.4.jar
curl https://repo1.maven.org/maven2/com/microsoft/azure/msal4j/1.11.0/msal4j-1.11.0.jar -o msal4j-1.11.0.jar
curl https://repo1.maven.org/maven2/com/nimbusds/content-type/2.1/content-type-2.1.jar -o content-type-2.1.jar
curl https://repo1.maven.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-xml/2.10.5/jackson-dataformat-xml-2.10.5.jar -o jackson-dataformat-xml-2.10.5.jar
curl https://repo1.maven.org/maven2/com/fasterxml/jackson/datatype/jackson-datatype-jsr310/2.10.5/jackson-datatype-jsr310-2.10.5.jar -o jackson-datatype-jsr310-2.10.5.jar
curl https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.6.0/kotlin-stdlib-1.6.0.jar -o kotlin-stdlib-1.6.0.jar
curl https://repo1.maven.org/maven2/com/nimbusds/oauth2-oidc-sdk/9.7/oauth2-oidc-sdk-9.7.jar -o oauth2-oidc-sdk-9.7.jar
curl https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.8.1/okhttp-4.8.1.jar -o okhttp-4.8.1.jar
curl https://repo1.maven.org/maven2/com/squareup/okio/okio/2.7.0/okio-2.7.0.jar -o okio-2.7.0.jar
curl https://repo1.maven.org/maven2/io/projectreactor/reactor-core/3.4.9/reactor-core-3.4.9.jar -o reactor-core-3.4.9.jar
curl https://repo1.maven.org/maven2/org/reactivestreams/reactive-streams/1.0.3/reactive-streams-1.0.3.jar -o reactive-streams-1.0.3.jar