control 'SV-253546' do
  title 'Prisma Cloud Compute Defender containers must run as root.'
  desc 'In certain situations, the nature of the vulnerability scanning may be more intrusive, or the container platform component that is the subject of the scanning may contain highly sensitive information. To protect the sensitive nature of such scanning, Prisma Cloud Compute Defenders perform the vulnerability scanning function. The Defender container must run as root and not privileged.'
  desc 'check', 'Verify that when deploying the Defender via daemonSet, "Run Defenders as privileged" is set to "On".

Verify the Defender containers were deployed using the daemonSet.yaml in which the securityContext is privileged.

If "Run Defenders as privileged" is not set to "On" or the Defender containers were not deployed using the daemonSet.yaml in which the securityContext - privileged = "on", this is a finding.'
  desc 'fix', 'Redeploy the Defender with appropriate rights by setting Run Defenders as privileged = off. 

Delete old twistlock-defender-ds daemonSet and redeploy daemonSet with the new yaml.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56998r840474_chk'
  tag severity: 'medium'
  tag gid: 'V-253546'
  tag rid: 'SV-253546r840476_rule'
  tag stig_id: 'CNTR-PC-001350'
  tag gtitle: 'SRG-APP-000414-CTR-001010'
  tag fix_id: 'F-56949r840475_fix'
  tag 'documentable'
  tag cci: ['CCI-001067']
  tag nist: ['RA-5 (5)']
end
