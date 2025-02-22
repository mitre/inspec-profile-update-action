control 'SV-250327' do
  title 'The WebSphere Liberty Server must be configured to offload logs to a centralized system.'
  desc 'Log processing failures include, but are not limited to, failures in the application server log capturing mechanisms or log storage capacity being reached or exceeded. In some instances, it is preferred to send alarms to individuals rather than to an entire group. Application servers must be able to trigger an alarm and send an alert to, at a minimum, the SA and ISSO in the event there is an application server log processing failure.

'
  desc 'check', 'As a privileged user with local file access to ${server.config.dir}/server.xml, verify the logstashCollector-1.0 feature is enabled.

grep -i -A5 logstashcollector server.xml

EXAMPLE:
<featureManager>
    <feature>logstashCollector-1.0</feature>
</featureManager>

<logstashCollector source="message,accessLog,audit"
          hostName="<ip address of logstash server>"
          port="<port of logstash server>"
          sslRef="DefaultTLSSettings"
  </logstashCollector>

If "logstashCollector" is not a configured feature and the logstashCollector "source" setting does not contain "message,accessLog,audit", this is a finding.'
  desc 'fix', 'To send Liberty logs to a centralized syslog system, the Elastic environment must be set up as per the ELK stack/Elasticsearch directions. Once that is completed, configure the server.xml. The following is a sample configuration. Individual keystore, truststore, and authentication settings will vary. The SME must substitute their own values as needed. 

The message, audit, and accessLog sources must be included at a minimum.

For additional information refer to the IBM website:
https://www.ibm.com/support/knowledgecenter/SSEQTP_liberty/com.ibm.WebSphere.wlp.doc/ae/twlp_analytics_logstash.html

EXAMPLE:

<featureManager>
    <feature>logstashCollector-1.0</feature>
</featureManager>

<keyStore id="defaultKeyStore" password="xxxxxxx" />
<keyStore id="defaultTrustStore" location="trust.jks" password="xxxxxxx" />
<ssl id="myTLSConfig" trustStoreRef="defaultTrustStore" keyStoreRef="defaultKeyStore" />

<logstashCollector 
source="message,accessLog,audit" 
hostName="your ELK stack server" 
port="Your ELK stack port" 
sslRef="myTLSConfig">
</logstashCollector>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53762r795032_chk'
  tag severity: 'medium'
  tag gid: 'V-250327'
  tag rid: 'SV-250327r795034_rule'
  tag stig_id: 'IBMW-LS-000230'
  tag gtitle: 'SRG-APP-000109-AS-000070'
  tag fix_id: 'F-53716r795033_fix'
  tag satisfies: ['SRG-APP-000109-AS-000070', 'SRG-APP-000358-AS-000064']
  tag 'documentable'
  tag cci: ['CCI-000140', 'CCI-001851']
  tag nist: ['AU-5 b', 'AU-4 (1)']
end
