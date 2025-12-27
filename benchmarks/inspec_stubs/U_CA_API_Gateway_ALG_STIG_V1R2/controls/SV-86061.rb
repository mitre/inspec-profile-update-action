control 'SV-86061' do
  title 'The CA API Gateway providing user authentication intermediary services using PKI-based user authentication must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

The intent of this requirement is to require support for a secondary certificate validation method using a locally cached revocation data, such as Certificate Revocation List (CRL), in case access to OCSP (required by CCI-000185) is not available. Based on a risk assessment, an alternate mitigation is to configure the system to deny access when revocation data is unavailable. 

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).

The CA API Gateway must implement a local cache of revocation data to support certificate validation in the event network access to the revocation server is unavailable. This cache must be created using a "Revocation Checking Policy" and be configurable to meet organizational requirements.'
  desc 'check', 'Open the CA API Gateway - Policy Manager, select "Tasks" from the main menu and chose "Manage Certificates". 

Click the "Certificate Validation" button and verify there is at least one Policy in the list of Revocation Checking Policies. 

Double-click one of the listed policies and verify the "Continue processing if server is unavailable" check box is checked. 

If there is no policy listed or the "Continue processing if server is unavailable" check box is not selected within the revocation policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager, select "Tasks" from the main menu, and chose "Manage Certificates". 

Click the "Certificate Validation" button and add a Revocation Check Policy in accordance with organizational requirements, making sure to select the "Continue processing if server is unavailable" check box within the policy. 

If a policy has already been added, open an existing policy and select the "Continue processing if server is unavailable" check box.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71437'
  tag rid: 'SV-86061r1_rule'
  tag stig_id: 'CAGW-GW-000640'
  tag gtitle: 'SRG-NET-000345-ALG-000099'
  tag fix_id: 'F-77755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
