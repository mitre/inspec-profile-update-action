control 'SV-15520' do
  title 'The name server software on production name servers is not BIND, Windows 2003 or later DNS, or alternatives with equivalent vendor support, configured in a manner to satisfy the general security requirements listed in the STIG. The only currently approved alternative is CISCO CSS DNS.'
  desc 'If an organization runs DNS name server software other than BIND, Windows 2003 DNS or later, or an equivalent alternative, it cannot benefit from assurance testing of those implementations of DNS. As a result, there may be unknown vulnerabilities associated with the alternative products for which there are no compensating controls. Moreover, there is no detailed security implementation guidance for other name server implementations, which makes it considerably harder to conduct reviews or self assessments. An incomplete review means that an organization operates at a lower level of assurance than could have been realized with one of the approved products.  Those products without vendor support can not be maintained at relevant security patch levels to assure the product has no vulnerabilities.'
  desc 'check', 'Validation of compliance with the requirements is determined via an operating system console.  An authorized SA should perform the required actions.  He or she will work side-by-side with the reviewer to determine which commands are most appropriate at certain points in the review.

UNIX

Instruction:  In the presence of the reviewer, the SA should enter the following command:

named –v 

or,

what /usr/sbin/named | grep named

If a version of BIND 9.4-ESV-R4, 9.6.2-P3, 9.6-ESV-R3, or  9.7.2-P3 above is not installed, then this is a finding.  If subsequent IAVA guidance recommends a BIND upgrade, then that guidance will supersede this requirement.

Windows (with BIND)

Instruction:  The reviewer must work with the SA to obtain the owner of the named.exe or dns.exe service.

In the presence of the reviewer, the SA should right-click on the named.exe or dns.exe service name file and select Properties | Version tab.

The version should be displayed in the “Description” field.

If a version of BIND prior to BIND 9.4-ESV-R4, 9.6.2-P3, 9.6-ESV-R3, 9.7.2-P3 is running, then this is a finding.  If subsequent IAVA guidance recommends a BIND upgrade, then that guidance will supersede this requirement.

Windows (Native)

Instruction:  The reviewer must ensure the operating system is Windows 2003 or later.  If it is not, then this is a finding.'
  desc 'fix', 'Working with DNS software administrators and other appropriate technical personnel, the IAO should oversee a migration to an approved name server software version.'
  impact 0.7
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-12986r1_chk'
  tag severity: 'high'
  tag gid: 'V-14763'
  tag rid: 'SV-15520r1_rule'
  tag stig_id: 'DNS0402'
  tag gtitle: 'Name server software does not meet the STIG reqs'
  tag fix_id: 'F-14233r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
