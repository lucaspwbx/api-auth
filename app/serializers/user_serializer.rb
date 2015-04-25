class UserSerializer < ActiveModel::Serializer
  attributes :id, :email, :created_at, :say_hello

  has_many :posts

  def say_hello
    "Hello #{object.email}"
  end
end
