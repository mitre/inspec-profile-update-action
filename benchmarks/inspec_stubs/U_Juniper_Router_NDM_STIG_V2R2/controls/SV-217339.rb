control 'SV-217339' do
  title 'The Juniper router must be configured to authenticate NTP sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the configuration example below.

system {
…
…
…
    }
    ntp {
        authentication-key 1 type md5 value "$8$LMK7NbHkPTQnVwF/"; ## SECRET-DATA
        authentication-key 2 type md5 value "$8$I3KceWbwgJUH"; ## SECRET-DATA
        server x.x.x.x key 1 prefer; ## SECRET-DATA
        server x.x.x.x key 2; ## SECRET-DATA
        trusted-key [1 2];
    }

If the router is not configured to authenticate NTP sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the router to authenticate NTP sources using authentication that is cryptographically based as shown in the example below.

[edit system ntp]
set authentication-key 1 type md5 value xxxxxxxxx
set authentication-key 2 type md5 value xxxxxxxxx
set server x.x.x.x key 1 prefer  
set server x.x.x.x key 2  
set trusted-key [1 2]

Note: SHA1 and SHA2-256 are supported with release 18.2.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18566r296595_chk'
  tag severity: 'medium'
  tag gid: 'V-217339'
  tag rid: 'SV-217339r855880_rule'
  tag stig_id: 'JUNI-ND-001140'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-18564r296596_fix'
  tag 'documentable'
  tag legacy: ['SV-101267', 'V-91167']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
