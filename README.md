# Elastic stack (ELK) + Syslog on Docker

By default, the stack exposes the following ports:

* 5044: Logstash Beats input
* 5000: Logstash TCP input
* 9600: Logstash monitoring API
* 9200: Elasticsearch HTTP
* 9300: Elasticsearch TCP transport
* 5601: Kibana


## Usage

**:warning: You must rebuild the stack images with `docker-compose build` whenever you switch branch or update the
[version](#version-selection) of an already existing stack.**

### Bringing up the stack

Clone this repository onto the Docker host that will run the stack, then start the stack's services locally using Docker
Compose:

```console
$ docker-compose up
```

*:information_source: You can also run all services in the background (detached mode) by appending the `-d` flag to the
above command.*

Give Kibana about a minute to initialize, then access the Kibana web UI by opening <http://localhost:5601> in a web
browser and use the following (default) credentials to log in:

* user: *elastic*
* password: *changeme*

*:information_source: Upon the initial startup, the `elastic`, `logstash_internal` and `kibana_system` Elasticsearch
users are intialized with the values of the passwords defined in the [`.env`](.env) file (_"changeme"_ by default). The
first one is the [built-in superuser][builtin-users], the other two are used by Kibana and Logstash respectively to
communicate with Elasticsearch. This task is only performed during the _initial_ startup of the stack. To change users'
passwords _after_ they have been initialized, please refer to the instructions in the next section.*
