control 'SV-68681' do
  title 'The ALG that is part of a CDS must have the capability to implement journaling.'
  desc 'A journaling file system is a file system that keeps track of the changes that will be made in a journal (usually a circular log in a dedicated area of the file system) before committing them to the main file system. In the event of a system crash or power failure, such file systems are quicker to bring back online and less likely to become corrupted.

The internal format of the journal must guard against crashes while the journal itself is being written to. Many journal implementations (such as the JBD2 layer in ext4) bracket every change logged with a checksum, on the understanding that a crash would leave a partially written change with a missing (or mismatched) checksum that can simply be ignored when replaying the journal at next remount.'
  desc 'check', 'If the ALG is not used as part of a CDS, this is not applicable.

Verify the ALG has the capability to implement journaling.

If the ALG does not have the capability to implement journaling, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to provide the capability to implement journaling.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55051r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54435'
  tag rid: 'SV-68681r1_rule'
  tag stig_id: 'SRG-NET-000511-ALG-000052'
  tag gtitle: 'SRG-NET-000511-ALG-000052'
  tag fix_id: 'F-59289r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
