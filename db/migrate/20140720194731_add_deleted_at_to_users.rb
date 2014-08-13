class AddDeletedAtToUsers < ActiveRecord::Migration
  def change
    add_column :users, :deleted_at, :datetime
  end
  def self.down
    raise ActiveRecord::IrreversibleMigration
  end
end
