Run the service:

```
./mvnw spring-boot:run
```

Trigger the endpoint that creates a dummy authorization record with access token issue time
just before the DST change:

```
curl localhost:8080/store-and-rea
```

This endpoint stored the record in Postgres and then tries to read it from the database. 
But the read operation fails with this exception:

```
2025-09-20T15:20:23.594+03:00 ERROR 72820 --- [nio-8080-exec-1] com.example.controller.TestController    : Error when find oauth2 authorization with id bf532958-242b-4076-ad30-81c35b48ffa5

java.lang.IllegalArgumentException: expiresAt must be after issuedAt
        at org.springframework.util.Assert.isTrue(Assert.java:116) ~[spring-core-6.2.11.jar:6.2.11]
        at org.springframework.security.oauth2.core.AbstractOAuth2Token.<init>(AbstractOAuth2Token.java:63) ~[spring-security-oauth2-core-6.5.5.jar:6.5.5]
        at org.springframework.security.oauth2.core.OAuth2AccessToken.<init>(OAuth2AccessToken.java:75) ~[spring-security-oauth2-core-6.5.5.jar:6.5.5]
        at org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService$OAuth2AuthorizationRowMapper.mapRow(JdbcOAuth2AuthorizationService.java:548) ~[spring-security-oauth2-authorization-server-1.5.2.jar:1.5.2]
        at org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService$OAuth2AuthorizationRowMapper.mapRow(JdbcOAuth2AuthorizationService.java:465) ~[spring-security-oauth2-authorization-server-1.5.2.jar:1.5.2]
        at org.springframework.jdbc.core.RowMapperResultSetExtractor.extractData(RowMapperResultSetExtractor.java:94) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.jdbc.core.RowMapperResultSetExtractor.extractData(RowMapperResultSetExtractor.java:61) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.jdbc.core.JdbcTemplate$1.doInPreparedStatement(JdbcTemplate.java:733) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.jdbc.core.JdbcTemplate.execute(JdbcTemplate.java:658) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:723) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:754) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:809) ~[spring-jdbc-6.2.11.jar:6.2.11]
        at org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService.findBy(JdbcOAuth2AuthorizationService.java:349) ~[spring-security-oauth2-authorization-server-1.5.2.jar:1.5.2]
        at org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService.findById(JdbcOAuth2AuthorizationService.java:296) ~[spring-security-oauth2-authorization-server-1.5.2.jar:1.5.2]
        at com.example.controller.TestController.storeAndReadToken(TestController.java:53) ~[classes/:na]
```
