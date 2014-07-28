module ApplicationHelper

  #
  # TFOR ALL PROTECTED APIS
  # Verify sign in is still valid
  # if not valid => 403
  #

  #
  # FOR SIGN IN ONLY (clear token to prevent sign in when token is stale for whatever reason)
  #
  # Note: It's assumed that this module is included from the controller, and hence the request
  # object is available at this point.
  #
  def clearStaleTokenBeforeSignIn

    myTestUserSignParams = User.new(sign_in_params)
    email = myTestUserSignParams.email
    userInfo = User.deleted.merge(User.active).select("id, email", "current_sign_in_at").where("email=?", email).limit(1)

    theUser = userInfo[0]
    if(theUser.blank?)

      #
      # We couldn't find a user with the given email => Just do a return here
      # Control will flow directly to the sign in controller which will handle
      # the sign-in failure appropriately.
      #

      STDOUT.write "clearStaleTokenBeforeSignIn(): User could not be found, can't check authentication token staleness and sign-in will fail in controller.\n"
      return
    end

    now = DateTime.now
    currentSignInAtActiveSupportTimeWithZone = theUser[:current_sign_in_at]
    currentSignInAtDateTime = currentSignInAtActiveSupportTimeWithZone.to_datetime

    tokenAgeDays = now - currentSignInAtDateTime
    tokenAgeMillis = (tokenAgeDays * 24 * 60 * 60 * 1000).to_i

    tokenTTLMS = Rails.application.config.auth_token_ttl_ms

    if(tokenAgeMillis > tokenTTLMS)
      staleTimeMS = tokenAgeMillis - tokenTTLMS
      STDOUT.write "clearStaleTokenBeforeSignIn(): The authentication token for user #{theUser.id} expired #{staleTimeMS} millis ago. Clearing the user's auth token to force new token generation\n"
      theUserId = theUser.id
      User.update(theUserId, :authentication_token => nil)
    end

    theUpdatedUser = User.deleted.merge(User.active).select("id, email", "current_sign_in_at", "authentication_token").where("email=?", email).limit(1)
  end

  def getLoggedInUser(request)
    token = request.headers['X-User-Token']
    userInfo = User.deleted.merge(User.active).select("id, email").where("authentication_token=?", token).limit(1)
    return userInfo[0]
  end

  #
  # Render JSON response for a user authentication
  #
  # If the user info is blank => 403, else 200
  #
  def renderAuthResponse(userInfo)

    #STDOUT.write "renderAuthResponse: userInfo = #{userInfo.inspect}"

    if(userInfo.blank?)
      render :status => 403, :json => I18n.t("token_verification_failed")
    else
      render :status => 200, :json => userInfo
    end
  end
end
