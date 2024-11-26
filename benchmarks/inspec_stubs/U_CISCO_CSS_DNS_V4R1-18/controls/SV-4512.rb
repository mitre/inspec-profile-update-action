control 'SV-4512' do
  title 'CSS DNS does not cryptographically authenticate APP sessions.'
  desc 'The risk to the CSS DNS in this situation is the CSS DNS peers do not authenticate each other, the sending and receiving of APP session data and peer communication may be with an adversary rather than the intended peer, thereby sending sensitive network architecture data and receiving ill intended zone data.  To protect against this possibility, the CSS DNS peers must cryptographically authenticate each other.'
  desc 'check', 'In the presence of the reviewer, the CSS DNS administrator should enter the following command while in global configuration mode:

show app session

Confirm the authentication type is set to “authChallenge” and the encryption type is set to “encryptMd5hash.”  This will confirm APP CHAP authentication and MD5 hashing features for APP sessions are configured between peers, if this is not the case, then this is a finding.  The only exception would be if the CSS DNS administrator uses an IPSEC VPN between each peer couple.  Review the IPSEC VPN with the CSS DNS administrator and validate the IPSEC VPN is configured between peers, if this is not the case, then this is a finding.'
  desc 'fix', 'The command, show app session, displays that the authentication type is not set to authChallenge and the encryption type is not set to encryptMd5hash.'
  impact 0.7
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3421r1_chk'
  tag severity: 'high'
  tag gid: 'V-4512'
  tag rid: 'SV-4512r1_rule'
  tag stig_id: 'DNS0915'
  tag gtitle: 'CSS DNS does not cryptographically authenticate.'
  tag fix_id: 'F-4397r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
end
