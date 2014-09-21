require 'test_helper'

class DevisePiecesDeactivatedLocalIntegrationTest < LocalIntegrationTest

  include PageNotFoundTests

  #
  # Verify that a bunch of devise MVC HTML controllers are disabled and give 404 page
  #
  test "Devise controllers are disabled in routes" do
    check_devise_pieces_deactivated
  end

end