control 'SV-75221' do
  title 'The Google Search Appliance must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, organizational users must be identified and authenticated. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Log on to the GSA Admin Console.

Select "Administration".

Select "User Accounts".

If there are individual "manager" and "admin" accounts per site specific organizational requirements, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Log on to the GSA Admin Console.

Select "Administration".

Select "User Accounts".

Create appropriate "manager" and "admin" accounts per site specific organizational requirement guidance.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60769'
  tag rid: 'SV-75221r1_rule'
  tag stig_id: 'GSAP-00-000455'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-66449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
