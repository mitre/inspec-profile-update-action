control 'SV-234141' do
  title 'The FortiGate firewall must protect traffic log records from unauthorized access while in transit to the central audit server.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or identify an improperly configured firewall. Thus, it is imperative that the collected log data be secured and access be restricted to authorized personnel. Methods of protection may include encryption or logical separation.

This does not apply to traffic logs generated on behalf of the device itself (management). Some devices store traffic logs separately from the system logs.'
  desc 'check', "Log in to the FortiGate GUI with Super-Admin privileges.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log syslogd setting | grep -i  'mode\\|server' 
The output should be:     
     set server {123.123.123.123}
     set mode reliable

To ensure a secure connection, a certificate must be loaded, encryption enabled, and the SSL version set. To verify, while still in the CLI, run the following command:
     # get log syslogd setting
Check for the following:
     set enc-algorithm {MEDIUM-HIGH | HIGH}
     set certificate

If the syslogd mode is not set to {reliable} and server IP address is not on the site's management network, this is a finding.
If the set enc-algorithm is not set to High or Medium-High, this is a finding.
If a certificate is not listed, this is a finding."
  desc 'fix', "Log in to the FortiGate GUI with Super-Admin privilege.

First, upload the organization CA certificate.
1. Click System.
2. Click Certificates.
3. Click Import, then CA Certificate.
4. Specify File, and click + Upload.
5. Choose the CA Certificate to upload from the local hard drive (base-64 format).
6. Click OK.

Note the name of the imported CA Certificate within the list of Remote CA Certificates.

Then, configure a TLS-enabled syslog connection:
1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log syslogd setting
     #    set status enable
     #    set server {CENTRAL SYSLOG SERVER IP ADDRESS} 
     #    set mode reliable
     #    set enc-algorithm {HIGH-MEDIUM | HIGH}
     #    set certificate {Certificate used to communicate with Syslog Server}
     # end

Note: The server IP address must be on the site's management network."
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37326r611421_chk'
  tag severity: 'medium'
  tag gid: 'V-234141'
  tag rid: 'SV-234141r628776_rule'
  tag stig_id: 'FNFG-FW-000050'
  tag gtitle: 'SRG-NET-000098-FW-000021'
  tag fix_id: 'F-37291r611422_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
