# frozen_string_literal: true

class ::Hash
  def merge_with_arrays_merged(newhash)
    merge(newhash) do |_key, oldval, newval|
      oldval.is_a?(Array) ? oldval | Array(newval) : newval
    end
  end
end
