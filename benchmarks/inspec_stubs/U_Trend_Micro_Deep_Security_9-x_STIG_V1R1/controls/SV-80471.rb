control 'SV-80471' do
  title 'Trend Deep Security must enforce access restrictions associated with changes to application configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure access restrictions associated with changes to application configuration are enforced.

Inspect the settings used for enforcing least privilege through access restrictions under Administration >> User Management >> Roles.

Select a role under the “Roles” menu and click "Properties". 

1. Select the “Computer Rights” tab and verify the settings configured under the “Computer and Group Rights” area. 

If non-authorized users have access to anything other than “View”, this is a finding. 

2. Select the “Policy Rights” tab and verify the settings configured under the “Policy Rights” area. 

If non-authorized users have access to anything other than “View,” this is a finding. 

3. Select the “User Rights” tab and verify the settings configured under the “User Rights” area. 

If non-authorized users have access to anything other than “Change own password and contact information only”, this is a finding. 

4. Select the Other Rights, tab and verify the settings configured under the “Other Rights” area. 

If non-authorized users have access to anything other than "View-Only" or "Hide", this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce access restrictions associated with changes to application configuration.

Enforce access restrictions associated with changes to application configuration. Under Administration >> User Management >> Roles, select a role and click “Properties”. 

1. Click Computer Rights >> Computer and Group Rights, and select only the “View” checkbox. 
2. Click Policy Rights >> Policy Rights, and select only the “View” checkbox.
3. Click User Rights >> User Rights, and select “Change own password and contact information only.”
4. Click Other Rights >> Other Rights, select "View-Only" or "Hide" for all options according to local policy for the roles permission.
5. Click "OK".'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65981'
  tag rid: 'SV-80471r1_rule'
  tag stig_id: 'TMDS-00-000295'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-72057r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
