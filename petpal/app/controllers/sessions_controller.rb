
########################################################
#
# This class provides authentication services
#
# Example of operations performed are:
#
# - Sign in - to obtain token
# - Sign out
# - Verify token
#
########################################################
class SessionsController < Devise::SessionsController

  # Required to for devise to not require the presence of an authenticity token
  skip_before_action :verify_authenticity_token, :only => [:create, :destroy]

  prepend_before_filter :require_no_authentication, :only => [:create]
  include Devise::Controllers::Helpers

  respond_to :json

  ################
  # Verify token
  # GET /user/token/verify
  # curl -X GET http://127.0.0.1:3000/user/token/verify -H "X-User-Token: m7X3PqsyifJ9VkshxLjn"
  ################
  def verify
    token = request.headers['X-User-Token']
    userInfo = User.deleted.merge(User.active).select("id, email").where("authentication_token=?", token).limit(1)

    if(userInfo.blank?)
      render :status => 403, :json => I18n.t("token_verification_failed")
    else
      # TODO: Refresh the expiration time of the token
      render :status => 200, :json => userInfo[0]
    end
  end

  ################
  # Sign in:
  # POST /user/login
  # curl -X POST http://127.0.0.1:3000/user/login.json -H "Content-Type: application/json" -d '{"user":{"email":"test@example.com", "password":"Test1234"}}'
  ################
  def create
    #
    # TODO: We need to limit this to active user scope only!!
    # It's currently possible to obtain auth tokens for deleted users
    #
    super
  end

  ################
  # Sign out:
  # DELETE /user/logout
  # curl -X DELETE http://127.0.0.1:3000/user/logout.json -H "X-User-Email: test@example.com" -H "X-User-Token: a6XK1qPfwyNd_HqjsgSS" -H "Content-Type: application/json"
  ################
  def destroy
    super
  end

end