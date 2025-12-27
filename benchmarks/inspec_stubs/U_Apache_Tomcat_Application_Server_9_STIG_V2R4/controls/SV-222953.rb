control 'SV-222953' do
  title 'DefaultServlet debug parameter must be disabled.'
  desc 'The DefaultServlet serves static resources as well as serves the directory listings (if directory listings are enabled). It is declared globally in $CATALINA_BASE/conf/web.xml and by default is configured with the "debug" parameter set to 0, which is disabled. Changing this to a value of 1 or higher sets the servlet to print debug level information. DefaultServlet debug setting must be set to 0 (disabled).'
  desc 'check', 'From the Tomcat server run the following OS command:

sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A10 -B2 defaultservlet 

The above command will include ten lines after and two lines before the occurrence of "defaultservlet". Some systems may require that the user increase the after number (A10) in order to determine the "debug" param-value. 

If the "debug" param-value for the "DefaultServlet" servlet class does not = 0, this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user:

Edit the $CATALINA_BASE/conf/web.xml file.

Examine the <init-param> elements within the <Servletclass> element, if the "debug" <param-value>element is not "0"" change the "debug" <param-value> to read "0".

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24625r426303_chk'
  tag severity: 'low'
  tag gid: 'V-222953'
  tag rid: 'SV-222953r615938_rule'
  tag stig_id: 'TCAT-AS-000510'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24614r426304_fix'
  tag 'documentable'
  tag legacy: ['SV-111431', 'V-102489']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
