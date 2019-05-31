## Wazuh
### Install Wazuh
### Configure Wazuh
In `/var/ossec/etc/ossec.conf` of the server:
+ Set the manager to listen on a specific IP address.
+
might disable some of the checksums

```xml
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>me@test.com</email_to>
    <smtp_server>mail.test.com..</smtp_server>
    <email_from>wazuh@test.com</email_from>
  </global>

  <alerts>
      <email_alert_level>10</email_alert_level>
  </alerts>

  <remote>
    <local_ip>10.0.0.10</local_ip>
  </remote>s

  <localfile>
    <location>/var/log/*.log</location>
    <log_format>syslog</log_format>
  </localfile>


  <reports>
    <category>syscheck</category>
    <title>Daily report: File changes</title>
    <email_to>example@test.com</email_to>
  </reports>
</ossec_config>
```
alerts.log and/or the alerts.json file(s).
