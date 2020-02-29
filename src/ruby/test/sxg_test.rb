require_relative "test_helper"
require "sxg"

class SxgTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Sxg::VERSION
  end

  def test_it_does_something_useful
    assert true
  end
end
