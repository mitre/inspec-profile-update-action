control 'SV-217052' do
  title 'The Juniper BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Review the BGP configuration to determine if it is peering with multiple autonomous systems.

Interview the ISSM and router administrator to determine if unique keys are being used. 

protocols {
    bgp {
        group AS44 {
            type external;
            peer-as 44;
            neighbor x.x.x.x {
                authentication-key "$8$tBga0ORx7VsYoIEgJ"; ## SECRET-DATA
            }
        }
        group AS66 {
            type external;
            peer-as 66;
            neighbor x.x.x.x {
                authentication-key "$8$Q4953nCrlMLX-9A7V"; ## SECRET-DATA
            }
        }
    }

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure the router to use unique keys for each AS that it peers with as shown in the example below.

[edit protocols bgp]
set group GROUP_AS66 authentication-key abc123
set group GROUP_AS44 authentication-key xyz123'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18281r297024_chk'
  tag severity: 'medium'
  tag gid: 'V-217052'
  tag rid: 'SV-217052r604135_rule'
  tag stig_id: 'JUNI-RT-000470'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-18279r297025_fix'
  tag 'documentable'
  tag legacy: ['SV-101099', 'V-90889']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
