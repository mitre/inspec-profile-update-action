control 'SV-34015' do
  title 'Web sites must utilize ports, protocols, and services according to PPSM guidelines.'
  desc 'Failure to comply with DoD ports, protocols, and services (PPS) requirements can result
in compromise of enclave boundary protections and/or functionality of the AIS.

The IAM will ensure web servers are configured to use only authorized PPS in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1, Ports, Protocols, and Services Management (PPSM), and the associated Ports, Protocols, and Services (PPS) Assurance Category Assignments List.'
  desc 'check', 'Review the web site to determine if HTTP and HTTPs are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM. If not, this is a finding.'
  desc 'fix', 'Ensure the web site enforces the use of IANA well-known ports for HTTP and HTTPS.'
  impact 0.3
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-30020r1_chk'
  tag severity: 'low'
  tag gid: 'V-15334'
  tag rid: 'SV-34015r1_rule'
  tag stig_id: 'WG610 A22'
  tag gtitle: 'WG610'
  tag fix_id: 'F-26863r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCPP-1'
end
