# frozen_string_literal: true

# allow(account).to read_buckets 'my-bucket'
#
# allow(account).to(
#   read_buckets('my-bucket').with(prefix('public/')),
#   read_objects('my-bucket/*', 'second-bucket/*')
# )
