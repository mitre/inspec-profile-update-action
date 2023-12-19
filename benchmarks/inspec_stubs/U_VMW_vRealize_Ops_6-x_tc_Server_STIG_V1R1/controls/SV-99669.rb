control 'SV-99669' do
  title 'tc Server CaSa must have the debug option turned off.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.

As a Tomcat derivative, tc Server can be configured to set the debugging level. By setting the debugging level to zero (0), no debugging information will be provided to a malicious user.  This provides a layer of defense to vROps.'
  desc 'check', %q(At the command prompt, execute the following command:

grep -En -A 2 -B 1 '<param-name>debug</param-name>' /usr/lib/vmware-casa/casa-webapp/conf/web.xml

If all instances of the debug parameter are not set to "0", this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/web.xml.

Navigate to all <debug> nodes that are not set to "0".

Set the <param-value> to "0" in all <param-name>debug</param-name> nodes.

Note: The debug setting should look like the below:

               <init-param>
                  <param-name>debug</param-name>
                  <param-value>0</param-value>
               </init-param>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89019'
  tag rid: 'SV-99669r1_rule'
  tag stig_id: 'VROM-TC-000705'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-95761r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
