control 'SV-222968' do
  title 'Tomcat must use FIPS-validated ciphers on secured connectors.'
  desc 'Connectors are how Tomcat receives requests over a network port, passes them to hosted web applications via HTTP or AJP, and then sends the results back to the requestor. Cryptographic ciphers are associated with the connector to create a secured connector. To ensure encryption strength is adequately maintained, the ciphers used must be FIPS 140-2-validated.

The FIPS-validated crypto libraries are not provided by Tomcat; they are included as part of the Java instance and the underlying Operating System. The STIG checks to ensure the FIPSMode setting is enabled for the connector and also checks the logs for FIPS errors, which indicates FIPS non-compliance at the OS or Java layers. The administrator is responsible for ensuring the OS and Java instance selected for the Tomcat installation provide and enable these FIPS modules so Tomcat can be configured to use them.

'
  desc 'check', 'From the Tomcat server console, run the following two commands to verify Tomcat server is configured to use FIPS:

sudo grep -i fipsmode $CATALINA_BASE/conf/server.xml

sudo grep -i fipsmode $CATALINA_BASE/logs/catalina.out

If server.xml  does not contain FIPSMode="on", or if catalina.out contains the error "failed to set property[FIPSMODE] to [on]", this is a finding.'
  desc 'fix', 'In addition to configuring Tomcat, the admin must also configure the underlying OS and Java engine to use FIPS validated encryption modules. This fix instructs how to enable FIPSMode within Tomcat, the OS and Java engine must be configured to use the FIPS validated modules according to the chosen OS and Java engine.
 
From the Tomcat server as a privileged user:

sudo nano $CATALINA_BASE/conf/server.xml.

In the <Listener/> element, locate the AprLifecycleListener. Either add or modify the FIPSMode setting and set it to FIPSMode="on".

EXAMPLE:
<Listener
   className="org.apache.catalina.core.AprLifecycleListener"
    SSLEngine="on"
    FIPSMode="on"
/>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24640r426348_chk'
  tag severity: 'high'
  tag gid: 'V-222968'
  tag rid: 'SV-222968r615938_rule'
  tag stig_id: 'TCAT-AS-000750'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-24629r426349_fix'
  tag satisfies: ['SRG-APP-000224-AS-000152', 'SRG-APP-000428-AS-000265', 'SRG-APP-000429-AS-000157', 'SRG-APP-000439-AS-000274', 'SRG-APP-000440-AS-000167']
  tag 'documentable'
  tag legacy: ['V-102609', 'SV-111567']
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002418', 'CCI-002421', 'CCI-002475', 'CCI-002476']
  tag nist: ['IA-7', 'SC-23 (3)', 'SC-8', 'SC-8 (1)', 'SC-28 (1)', 'SC-28 (1)']
end
