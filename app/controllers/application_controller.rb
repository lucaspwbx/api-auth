class ApplicationController < ActionController::API
  include ::ActionController::Serialization
  include ActionController::HttpAuthentication::Basic::ControllerMethods
  include ActionController::HttpAuthentication::Token::ControllerMethods

  before_filter :authenticate_user_from_token, except: [:token]

  def default_serializer_options
    { root: false }
  end

  def authenticate_user_from_token
    authenticate_with_http_token do |token, _|
      user = User.find_by(auth_token: token)
      render json: { error: 'Bad Token' } unless user
    end
  end

  def token
    authenticate_with_http_basic do |email, password|
      user = User.find_by(email: email)
      if user && user.password == password
        render json: { token: user.auth_token }
      else
        render json: { errors: 'Incorrect credentials' }, status: 401
      end
    end
  end
end
