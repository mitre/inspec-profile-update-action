control 'SV-233865' do
  title 'All authoritative name servers for a zone must have the same version of zone information.'
  desc 'The only protection approach for content control of DNS zone file is the use of a zone file integrity checker. The effectiveness of integrity checking using a zone file integrity checker depends on the database of constraints built into the checker. The deployment process consists of developing these constraints with the right logic, and the only determinant of the truth value of these logical predicates is the parameter values for certain key fields in the format of various RRTypes.

The serial number in the SOA RDATA is used to indicate to secondary name servers that a change to the zone has occurred and a zone transfer should be performed. It should always be increased whenever a change is made to the zone data. DNS NOTIFY must be enabled on the master authoritative name server.'
  desc 'check', 'Review DNS zone data to validate the SOA on all authoritative DNS servers. Remote name servers that do not have the same serial number as the primary name server may have network issues or misconfiguration blocking updates.  

Use either the "nslookup" or "dig" utility to review the serial number returned from each name server. 

Example: 
Using the "dig" utility, enter the command line as follows: "dig @NAMESERVER-IP ZONE SOA".   $ dig @192.168.0.1 blue.org SOA  ;; ANSWER SECTION: blue.org.  28800 IN SOA ns.blue.org. postmaster.blue.org. 20200922 10800 3600 2419200 900  

The SOA RR specifies the serial number as the third RDATA field; in this example, it is 20200922.  

If any serial numbers for the same zone do not match, this is a finding.'
  desc 'fix', 'Serial numbers are updated automatically when changes are made to a zone through the Infoblox Grid, as well as through the notify process for external DNS servers. If a serial number mismatch is discovered, troubleshooting of both server configurations and network will be required. Protocol configuration issues will be logged in the Infoblox Grid Members SYSLOG.  

1. Navigate to Administration >> Logs >> Syslog.  
2. Infoblox Grid Members can be selected using the drop-down menu.  
3. Stand-alone systems will not display a drop-down menu; the log data will be displayed automatically.  
4. Review the SYSLOG data and resolve the issue that is preventing updates.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37050r611115_chk'
  tag severity: 'medium'
  tag gid: 'V-233865'
  tag rid: 'SV-233865r621666_rule'
  tag stig_id: 'IDNS-8X-400007'
  tag gtitle: 'SRG-APP-000516-DNS-000088'
  tag fix_id: 'F-37015r611116_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
