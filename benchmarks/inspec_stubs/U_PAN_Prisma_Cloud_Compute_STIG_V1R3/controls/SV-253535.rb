control 'SV-253535' do
  title 'All Prisma Cloud Compute users must have a unique, individual account.'
  desc 'Prisma Cloud Compute does not have a default account. During installation, the installer creates an administrator. This account can be removed once other accounts have been added. To ensure accountability and prevent unauthenticated access, users must be identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', %q(Confirm there is only one "break glass" local administrative account. 

Navigate to Prisma Cloud Compute Console's Manage >> Authentication >> Users tab. 

Only the administrative break glass account is allowed to have Authentication Method = Local. 

For all other accounts, Authentication Method = SAML.

If any local account, except the administrative break glass account, has Authentication Method set to other than "SAML", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Users tab.

Ensure only the break glass administrator account is a "local" account. 

Delete all other local accounts and use the SAML identity provider for all authentication and authorization to the Prisma Cloud Compute Console.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56987r840441_chk'
  tag severity: 'medium'
  tag gid: 'V-253535'
  tag rid: 'SV-253535r879589_rule'
  tag stig_id: 'CNTR-PC-000510'
  tag gtitle: 'SRG-APP-000148-CTR-000335'
  tag fix_id: 'F-56938r840442_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
