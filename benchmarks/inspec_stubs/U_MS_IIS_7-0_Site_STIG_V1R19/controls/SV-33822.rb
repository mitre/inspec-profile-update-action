control 'SV-33822' do
  title 'Web sites must utilize ports, protocols, and services according to PPSM guidelines.'
  desc 'Failure to comply with DoD ports, protocols, and services (PPS) requirements can result
in compromise of enclave boundary protections and/or functionality of the AIS.

The IAM will ensure web servers are configured to use only authorized PPS in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1, Ports, Protocols, and Services Management (PPSM), and the associated Ports, Protocols, and Services (PPS) Assurance Category Assignments List.'
  desc 'check', 'Review the web site to determine if HTTP and HTTPs (e.g., 80 and 443) are used in accordance with those ports and services registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM.

1. Open the IIS Manager.
2. Click the site name under review.
3. In the Action Pane, click Bindings.
4. Review the ports and protocols. If unknown ports or protocols are used, then this is a finding.'
  desc 'fix', 'Ensure the web site enforces the use of HTTP and HTTPS in accordance with PPSM guidance.

1. Open the IIS Manager.
2. Click the site name under review.
3. In the Action Pane, click Bindings.
4. Edit to change an existing binding and set the correct ports and protocol.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-33501r2_chk'
  tag severity: 'low'
  tag gid: 'V-15334'
  tag rid: 'SV-33822r2_rule'
  tag stig_id: 'WG610 IIS7'
  tag gtitle: 'WG610'
  tag fix_id: 'F-29201r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
