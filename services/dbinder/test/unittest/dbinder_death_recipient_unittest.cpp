#include "dbinder_service.h"
#include "gtest/gtest.h"
#include "rpc_log.h"
#include "log_tags.h"
#include "session_impl.h"
#define private public
#include "dbinder_death_recipient.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HiviewDFX;
using Communication::SoftBus::Session;
using Communication::SoftBus::SessionImpl;

class DbinderDeathRecipientUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_ID_RPC, "DBinderRemoteListenerUnitTest" };
};

void DbinderDeathRecipientUnitTest::SetUp() {}

void DbinderDeathRecipientUnitTest::TearDown() {}

void DbinderDeathRecipientUnitTest::SetUpTestCase() {}

void DbinderDeathRecipientUnitTest::TearDownTestCase() {}

HWTEST_F(DbinderDeathRecipientUnitTest, OnRemoteDied001, TestSize.Level1)
{
    DbinderDeathRecipient dbinderDeathRecipient;
    wptr<IRemoteObject> remote = nullptr;
    dbinderDeathRecipient.OnRemoteDied(remote);
}