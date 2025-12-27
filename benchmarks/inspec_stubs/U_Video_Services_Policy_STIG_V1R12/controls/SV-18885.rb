control 'SV-18885' do
  title 'VTC system and endpoint users must sign a user agreement when accepting an endpoint or obtaining approval to use an endpoint.'
  desc 'Users must read and sign a user agreement before receiving their government furnished hardware, software, or gaining access to a system, application, or additional privilege on a VTC system or endpoint. The rules of use and operational procedures for VTC endpoints of all types must be affirmed by users. Each endpoint type will or may require different rules and procedures. Users must be informed of the vulnerabilities and risks of VTC endpoint use and trained in the procedures required to mitigate them as described in the training requirement. Furthermore, users must acknowledge their awareness of the IA issues and mitigating requirements and their agreement to abide by the rules of operation of the VTC endpoint or system. This user agreement must restate the elements of the required training and serve as an acknowledgement that the training was received. This user agreement can also include a statement of the penalties for non-compliance with the rules of operation.'
  desc 'check', 'Review site documentation to confirm a policy and procedure requires the VTC system and endpoint users must sign a user agreement when accepting an endpoint or obtaining approval to use an endpoint. Inspect the user agreement to confirm it contains the following at minimum: 
- Acknowledgement of their awareness of the vulnerabilities and risks associated with the use of the specific VTC system or devices the user is receiving, will receive, or use.
- Acknowledgement of their awareness of the methods contained in the SOP and training materials intended to mitigate the vulnerabilities and risks 
- Agreement to operate the system in a secure manner and employ the methods contained in the SOP and training materials intended to mitigate the vulnerabilities and risks
- Acknowledgement of the penalties for non-compliance with the rules of operation if stated in the agreement.
- Acknowledgement of their awareness of the capability (or lack thereof) of the system to provide assured service for C2 communications

If a policy and procedure requiring the VTC system and endpoint users to sign a user agreement when accepting an endpoint or obtaining approval to use an endpoint does not exist, this is a finding. If the user agreement does not, at minimum, contain the above, this is a finding.'
  desc 'fix', 'Implement a policy and procedure providing VTC system and endpoint users must sign a user agreement when accepting an endpoint or obtaining approval to use an endpoint. Maintain copies of the signed user agreements and provide a copy to the user for their reference.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18981r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17711'
  tag rid: 'SV-18885r2_rule'
  tag stig_id: 'RTS-VTC 3720.00'
  tag gtitle: 'RTS-VTC 3720'
  tag fix_id: 'F-17608r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
