#ifndef POLICYMANAGER_H
#define POLICYMANAGER_H

#include "baseeventreceiver.h"
#include "threadsafequeue.h"
#include "baseevent.h"
#include "addevent.h"
#include "removeevent.h"
#include "timerevent.h"
#include "monitorevent.h"
#include "feedbackevent.h"
#include "securityevent.h"
#include "appmapping.h"
#include "policies/ibasepolicy.h"
#include "platformdescription.h"
#include <log4cpp/Category.hh>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>

namespace rmcommon {
class EventBus;
}

namespace rp {

/*!
 * Using the EventBus, PolicyManager receives events from multiple
 * threads, adds/removes managed applications to
 * a set and forwards the events to the chosen resource
 * policy.
 */
class PolicyManager : public rmcommon::BaseEventReceiver {
public:
    enum class Policy {
        NoPolicy,
        RandPolicy,
        PuProgressivePolicy,
        MinCoresPolicy
    };

private:
    log4cpp::Category &cat_;
    rmcommon::EventBus &bus_;
    std::unique_ptr<IBasePolicy> policy_;
    PlatformDescription platformDescription_;
    AppMappingSet apps_;

    /*! Set of the PIDs (in Konro's namespace) of apps */
    using PidSet = std::set<pid_t>;
    /*! Node (e.g. a worker) -> PIDs of the apps running on it */
    std::map<std::string, PidSet> nodeMap_;
    /*! Source node (e.g. a sensor) -> PIDs of the apps that read data from it */
    std::map<std::string, PidSet> sourceMap_;
    /*! Names of the nodes reported as compromised */
    std::set<std::string> compromisedNodes_;

    /*! Adds the app to nodeMap_ and sourceMap_, using its node and sources */
    void indexApp(const AppMappingPtr &appMapping);

    /*! Removes the app (by PID) from nodeMap_ and sourceMap_ */
    void unindexApp(const AppMappingPtr &appMapping);

    /*! Returns the managed app with the specified PID, nullptr if not present */
    AppMappingPtr findAppByPid(pid_t pid) const;

    /*! Returns the managed apps running on the specified node */
    std::vector<AppMappingPtr> appsOnNode(const std::string &node) const;

    /*! Returns the managed apps that read data from the specified source */
    std::vector<AppMappingPtr> appsFedBy(const std::string &source) const;

    void subscribeToEvents();

    /*!
     * Processes a generic event by calling the appropriate handler function.
     * \param event the event to process
     */
    bool processEvent(std::shared_ptr<const rmcommon::BaseEvent> event) override;

    /*!
     * Processes an AddEvent.
     * \param event the event to process
     */
    void processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event);

    /*!
     * Processes an SecurityEvent.
     * \param event the event to process
     */
    void processSecurityEvent(std::shared_ptr<const rmcommon::SecurityEvent> event);

    /*!
     * Processes a RemoveEvent.
     * \param event the event to process
     */
    void processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event);

    /*!
     * Processes a TimerEvent
     * \param ev the event to process
     */
    void processTimerEvent(std::shared_ptr<const rmcommon::TimerEvent> event);

    /*!
     * Processes a MonitorEvent
     * \param ev the event to process
     */
    void processMonitorEvent(std::shared_ptr<const rmcommon::MonitorEvent> event);

    /*!
     * Processes a FeedbackEvent
     * \param ev the event to process
     */
    void processFeedbackEvent(std::shared_ptr<const rmcommon::FeedbackEvent> event);

    /* for debugging */
    void dumpApps() const;

    /*! Factory method */
    std::unique_ptr<IBasePolicy> makePolicy(Policy policy);
public:

    PolicyManager(rmcommon::EventBus &bus, PlatformDescription pd, Policy policy = Policy::NoPolicy);
    virtual ~PolicyManager() = default;

    /*!
     * Return the policy with the specified name.
     * If no policy exists with that name, NoPolicy is returned.
     */
    static Policy getPolicyByName(const std::string &policyName);
};

}   // namespace rp

#endif // POLICYMANAGER_H
