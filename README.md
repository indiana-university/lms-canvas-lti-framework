# LMS Canvas LTI Framework Services

When this library is added to a project it allows for LTI framework service details to be setup.

## Installation
### From Maven
Add the following as a dependency in your pom.xml
```xml
<dependency>
    <groupId>edu.iu.uits.lms</groupId>
    <artifactId>lms-canvas-lti-framework</artifactId>
    <version><!-- latest version --></version>
</dependency>
```

You can find the latest version in [Maven Central](https://search.maven.org/search?q=g:edu.iu.uits.lms%20AND%20a:lms-canvas-lti-framework).

## Setup Examples
### Include annotation to enable to the configs
Add to any configuration class, or even the main application class `@EnableLtiClient`.

Once that has been done, you can autowire in and use any canvas service.  Generally, you won't use them directly, but they are used in the default LTI Controller that you will extend.

### Create a controller that extends LtiController
This controller will handle the LTI launches from canvas, then redirect to your tool's main controller (via launch url below).
```java
// example lti controller
public class MyToolLtiController extends LtiController {
   @Override
   protected String getLaunchUrl(Map<String, String> paramMap) {
      String courseId = launchParams.get(CUSTOM_CANVAS_COURSE_ID);
      return courseId + "/index";
   }

   @Override
   protected Map<String, String> getParametersForLaunch(Map<String, String> payload, Claims claims) {
      Map<String, String> paramMap = new HashMap<String, String>(1);

      paramMap.put(CUSTOM_CANVAS_COURSE_ID, payload.get(CUSTOM_CANVAS_COURSE_ID));
      paramMap.put(BasicLTIConstants.ROLES, payload.get(BasicLTIConstants.ROLES));
      paramMap.put(CUSTOM_CANVAS_USER_LOGIN_ID, payload.get(CUSTOM_CANVAS_USER_LOGIN_ID));

      return paramMap;
   }

   @Override
   protected String getToolContext() {
      return "my_tool_context";
   }
}
```
There are other overridable methods that might be of interest.  Take a look and see!

## Setup Database
After compiling, see `target/generated-resources/sql/ddl/auto/postgresql9.sql` for appropriate ddl.
Insert a record into the `LTI_AUTHZ` table with a key and secret.  The context should be defined by your tool's `getToolContext()` method, as implemented in the example above.
A wildcard (`*`) is also acceptable in the database and is useful for testing multiple tools, but may not be recommended in production environments.

## Configuration
If choosing to use properties files for the configuration values, the default location is `/usr/src/app/config`, but that can be overridden by setting the `app.fullFilePath` value via system property or environment variable.

### Database Configuration
The following properties need to be set to configure the communication with a database.
They can be set in a security.properties file, or overridden as environment variables.

| Property | Description |
|-------|----------------|
| `lms.db.user`         | Username used to access the database |
| `lms.db.url`          | JDBC URL of the database.  Will have the form `jdbc:<host>:<port>/<database>` |
| `lms.db.driverClass`  | JDBC Driver class name |
| `lms.db.password`     | Password for the user accessing the database |
