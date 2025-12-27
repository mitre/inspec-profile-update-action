control 'SV-253777' do
  title 'MariaDB must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the DBMS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

In addition to this STIG, sources of guidance on security and information assurance include NSA configuration guides, CTOs, DTMs, and IAVMs. The DBMS must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', 'Review the MariaDB documentation and configuration to determine if MariaDB is configured in accordance with DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.

If MariaDB is not configured in accordance with security configuration settings, this is a finding.'
  desc 'fix', 'Configure MariaDB in accordance with DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs and IAVMs.

If MariaDB is not configured in accordance with security configuration settings, this is a finding.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57229r841854_chk'
  tag severity: 'medium'
  tag gid: 'V-253777'
  tag rid: 'SV-253777r841856_rule'
  tag stig_id: 'MADB-10-012500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-57180r841855_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
