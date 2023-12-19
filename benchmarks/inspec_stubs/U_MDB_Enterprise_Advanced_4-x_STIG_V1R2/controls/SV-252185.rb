control 'SV-252185' do
  title 'MongoDB must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring MongoDB to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. MongoDB must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', 'Assessing the system against the STIG configurations and guidance of the current document is the check for this requirement. 

If the MongoDB is not configured in accordance with the security configuration settings of this document, this is a finding.'
  desc 'fix', 'Configure MongoDB in accordance with security configuration settings and guidance of this STIG document to meet the configurations required by the STIG, NSA configuration guidelines, CTOs, DTMs, and IAVMs.

It is recommended that MongoDB Enterprise be installed and upgraded though the use of a package manager (YUM/RPM RedHat) where it meets the organizational or site-specific policy: 
https://docs.mongodb.com/v4.4/tutorial/install-mongodb-enterprise-on-red-hat/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55641r813935_chk'
  tag severity: 'medium'
  tag gid: 'V-252185'
  tag rid: 'SV-252185r816999_rule'
  tag stig_id: 'MD4X-00-006600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-55591r816998_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
