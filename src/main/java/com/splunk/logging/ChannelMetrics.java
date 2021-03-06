/*
 * Copyright 2017 Splunk, Inc..
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.splunk.logging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.Observable;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 *
 * @author ghendrey
 */
public class ChannelMetrics extends Observable {
  private static final ObjectMapper mapper = new ObjectMapper();
  private final ConcurrentMap<Long, Long> birthTimes = new ConcurrentSkipListMap<>(); //ackid -> creation time
  private long oldestUnackedBirthtime = Long.MIN_VALUE;
  private long mostRecentTimeToSuccess = 0;
  
  @Override
  public String toString(){
    try {
      return "METRICS ---> "+mapper.writeValueAsString(this);
    } catch (JsonProcessingException ex) {
      throw new RuntimeException(ex.getMessage(), ex);
    }
  }

  public void ackIdCreated(long ackId) {
    long birthtime = System.currentTimeMillis();
    birthTimes.put(ackId, birthtime);
    if (oldestUnackedBirthtime == Long.MIN_VALUE) { //not set yet id MIN_VALUE
      oldestUnackedBirthtime = birthtime; //this happens only once. It's a dumb firt run edgecase
      this.setChanged();
      this.notifyObservers();
    }
  }

  public void ackIdSucceeded(Collection<Long> succeeded) {
    succeeded.forEach((Long e) -> { //yeah! gratuitous use of streams!!
      Long birthTime;
      if (null != (birthTime = birthTimes.remove(e))) {
        this.mostRecentTimeToSuccess = System.currentTimeMillis() - birthTime;
        if (oldestUnackedBirthtime == this.mostRecentTimeToSuccess) { //in this case we just processed the oldest ack
          oldestUnackedBirthtime = scanForOldestUnacked();//so we need to figure out which unacked id is now oldest
        }
      } else {
        throw new IllegalStateException("no birth time recorder for ackId: " + e);
      }
    });
    this.setChanged();
    this.notifyObservers();
  }

  private long scanForOldestUnacked() {
    long oldest = Long.MAX_VALUE;
    for (long birthtime : birthTimes.values()) { //O(n) acceptave 'cause window gonna be small
      if (birthtime < oldest) {
        oldest = birthtime;
      }
    }
    return oldest;
  }

  /**
   * @return the unacknowledgedCount
   */
  public int getUnacknowledgedCount() {
    return birthTimes.size();
  }

  public String getOldest(){
    return new Date(oldestUnackedBirthtime).toString();
  }

  /**
   * @return the mostRecentTimeToSuccess
   */
  public String getMostRecentTimeToSuccess() {
    return Duration.ofMillis(mostRecentTimeToSuccess).toString();
  }

}
