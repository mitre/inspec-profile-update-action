control 'SV-223646' do
  title 'Certificate Name Filtering must be implemented with appropriate authorization and documentation.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Currently the RACDCERT command does not support a generic userid value of ID(*) LISTMAP to list all the certificate name filters defined to RACF. However, the following commands can be issued to determine if certificate name filtering may be implemented.

If certificate name filtering is in use, collect documentation describing each active filter rule and written approval from the ISSM to use the rule.

Issue the SETROPTS LIST command. If the DIGTNMAP resource class is active, RACF is ready to process any certificate name filters with a Status of TRUST. The DIGTNMAP resource class should not be active unless certificate name filtering is desired.

If the DIGTNMAP resource class is not active, this is not a finding.

Certificate name filters are stored as profiles in the DIGTNMAP resource class. The RLIST command is not intended for use with profiles in the DIGTNMAP resource class. However it can be used to determine if any profiles are defined. (NOTE: The information will not be displayed in a suitable format to easily interpret the filter.) 

RLIST DIGTNMAP *

If there is nothing to list in the DIGTNMAP resource class, this is not a finding.

If profile information is displayed, one or more certificate name filters are defined to RACF. Under the NAME heading of each profile listing is the userid the filter is being mapped to. Issue the following command the list the certificate name filter associated with each userid:

RACDCERT ID(profile name userid) LISTMAP

NOTE: Certificate name filters are only valid when their Status is TRUST. Therefore, you may ignore filters with the NOTRUST status.

If the DIGTNMAP resource class is active and certificate name filters have a Status of TRUST, certificate name filtering is in use.

If certificate name filtering is in use and filtering rules have been documented and approved by the ISSM, this is not a finding.

If certificate name filtering is in use and filtering rules have not been documented and approved by the ISSM, this is a finding.'
  desc 'fix', 'Ensure any certificate name filtering rules in use are documented and approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25319r514627_chk'
  tag severity: 'medium'
  tag gid: 'V-223646'
  tag rid: 'SV-223646r604139_rule'
  tag stig_id: 'RACF-CE-000010'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25307r514628_fix'
  tag 'documentable'
  tag legacy: ['V-97997', 'SV-107101']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
