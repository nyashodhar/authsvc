###################################################
#
# The purpose of this controller is to ensure that
# all 404 and 500 errors that encountered by the
# application are rendered as JSON, not HTML
#
###################################################
class ErrorsController < ActionController::Base
  def not_found
      render :status => 404, :json => {:error => "not-found"}.to_json
  end

  def exception
      render :status => 500, :json => {:error => "internal-server-error"}.to_json
  end
end