# seattle-open-data-spring-cloud-config-server
## JWT minded Configuration Integration for Spring Cloud Config Server - Sample Project for Seattle 911 calls Open Data

### Features 
Config Server uses JWT authentication approach instead of standard Basic Authentication. Please keep in mind Spring Cloud Config Client needs some changes too. [Find code here](https://github.com/ka4ok85/spring-cloud-config-client-jwt)

Authentication flow has following steps:
  1. Client sends request with username/password to Server's Authentication REST Controller.
  2. Server returns back JWT.
  3. Client includes Token with *Bearer:* prefix into *Authorization* Header for querying configuration values from Config Server.

### Usage 
  1. All JWT-related configuruation happens on Client side. Please use standard Spring Cloud Config Server configuration.
