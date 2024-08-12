import { MongoClient } from 'mongodb';

async function migrateData() {
  // Source database configuration
  const sourceUri = 'mongodb+srv://admin:NLJ9R6Xz6Zw6ECOYkzSJWnAtrhhify2g@signia-serverless.be2miu7.mongodb.net/?retryWrites=true&w=majority';
  const sourceDbName = 'production_signia_lookupService';
  const sourceCollectionName = 'signiaRecords';

  // Target database configuration
  const targetUri = 'mongodb+srv://admin:NLJ9R6Xz6Zw6ECOYkzSJWnAtrhhify2g@signia-serverless.be2miu7.mongodb.net/?retryWrites=true&w=majority';
  const targetDbName = 'production_overlay_services';
  const targetCollectionName = 'signiaRecords';

  const sourceClient = new MongoClient(sourceUri);
  const targetClient = new MongoClient(targetUri);

  try {
    // Connect to source and target clients
    await sourceClient.connect();
    await targetClient.connect();

    const sourceDb = sourceClient.db(sourceDbName);
    const targetDb = targetClient.db(targetDbName);

    const sourceCollection = sourceDb.collection(sourceCollectionName);
    const targetCollection = targetDb.collection(targetCollectionName);

    // Fetch records from source collection
    const records = await sourceCollection.find().toArray();

    if (records.length > 0) {
      // Insert records into target collection
      const result = await targetCollection.insertMany(records);
      console.log(`Successfully inserted ${result.insertedCount} records to the target collection.`);
    } else {
      console.log('No records found in the source collection.');
    }
  } catch (error) {
    console.error('An error occurred during data migration:', error);
  } finally {
    // Close the connections
    await sourceClient.close();
    await targetClient.close();
  }
}

migrateData().catch(console.error);
