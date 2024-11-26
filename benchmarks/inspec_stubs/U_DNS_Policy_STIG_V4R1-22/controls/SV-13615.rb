control 'SV-13615' do
  title 'The name server software on production name servers is not BIND, Windows 2003 or later DNS, or alternatives with equivalent security functionality and support, configured in a manner to satisfy the general security requirements listed in the STIG.'
  desc 'If an organization runs DNS name server software other than BIND,  Windows 2003 DNS or later, or an equivalent alternative, such as Infoblox running BIND; it cannot benefit from assurance testing of those implementations of DNS.  As a result, there may be unknown vulnerabilities associated with the alternative product for which there are no compensating controls.  Moreover, there is no detailed security implementation guidance for other name server implementations, which makes it considerably harder to conduct reviews or self assessments.  An incomplete review means that an organization operates at a lower level of assurance than could have been realized with one of the approved products.'
  desc 'check', 'Review the DNS name server software on the platform to determine what DNS software is running.  If the name server is running a DNS implementation other than ISC BIND, Windows 2003 or later DNS, or equivalent DNS dedicated device such as Infoblox, then this is a finding. 

Cisco CSS DNS is limited to only those hosts defined in the csd.disa.mil domain. CSS DNS is subject both to these general security requirements, where applicable, and the specific STIG guidance for this product.'
  desc 'fix', 'Working with DNS software administrators and other appropriate technical personnel, the IAO should oversee a migration to an approved name server software.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3476r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13047'
  tag rid: 'SV-13615r1_rule'
  tag stig_id: 'DNS0400'
  tag gtitle: 'Incorrect name server software.'
  tag fix_id: 'F-4356r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
