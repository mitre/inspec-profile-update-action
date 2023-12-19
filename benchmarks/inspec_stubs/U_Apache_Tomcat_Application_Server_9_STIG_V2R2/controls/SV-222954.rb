control 'SV-222954' do
  title 'DefaultServlet directory listings parameter must be disabled.'
  desc 'The DefaultServlet serves static resources as well as directory listings. It is declared globally in $CATALINA_BASE/conf/web.xml and by default is configured with the directory "listings" parameter set to disabled. If no welcome file is present and the "listings" setting is enabled, a directory listing is shown. Directory listings must be disabled.'
  desc 'check', 'From the Tomcat server run the following OS command:

sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A10 -B2 defaultservlet 

The above command will include ten lines after and two lines before the occurrence of "defaultservlet". Some systems may require that the user increase the after number (A10) in order to determine the "listings" param-value. 

If the "listings" param-value for the "DefaultServlet" servlet class does not = "false", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user:

Edit the $CATALINA_BASE/conf/web.xml file.

Examine the <init-param> elements within the <Servletclass> element, if the "listings" <param-value>element is "true" change the "listings" <param-value> to read "false".

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24626r426306_chk'
  tag severity: 'low'
  tag gid: 'V-222954'
  tag rid: 'SV-222954r615938_rule'
  tag stig_id: 'TCAT-AS-000520'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24615r426307_fix'
  tag 'documentable'
  tag legacy: ['SV-111433', 'V-102491']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
